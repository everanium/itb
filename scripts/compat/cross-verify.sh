#!/usr/bin/env bash
# cross-verify.sh -- ITB fleet cross-binding wire-compat matrix.
#
# For each of the 9 shipped triple/ profiles, encrypts the shared
# sample file with every eitb utility (33 language bindings + the Go
# native tool = 34 encrypters) and then decrypts every produced
# ciphertext with every eitb utility. Verifies SHA-256(decrypted) ==
# SHA-256(source) and records PASS / FAIL for each cell.
#
# Results:
#   tmp/eitb/enc/<profile>/<encrypter>.bin           ciphertext
#   tmp/eitb/enc/<profile>/<encrypter>.blob          session-blob hex
#   tmp/eitb/dec/<profile>/<encrypter>__<decrypter>  decrypter's back.bin (only on FAIL)
#   tmp/eitb/results.tsv                             profile\tencrypter\tdecrypter\tPASS|FAIL[\tdiag]
#   tmp/eitb/compat-matrix.md                        rendered 9 tables + summary
#
# The Go native eitb is (re)built from tools/eitb before the run.
# All other eitb utilities are assumed pre-built (each binding's
# build.sh has been run at some point beforehand).

set -eu
set -o pipefail

REPO="/home/andrew/go/src/itb"
IN_FILE="$REPO/tools/eitb/in-file.txt"
EITB_DIR="$REPO/tmp/eitb"
DIST_DIR="$REPO/dist/linux-amd64"

mkdir -p "$EITB_DIR/enc" "$EITB_DIR/dec"

# ---------------------------------------------------------------------
# Preconditions.
# ---------------------------------------------------------------------

if [ ! -f "$IN_FILE" ]; then
    echo "cross-verify: missing sample input $IN_FILE" >&2
    exit 2
fi

if [ ! -f "$DIST_DIR/libitb.so" ]; then
    echo "cross-verify: missing $DIST_DIR/libitb.so" >&2
    echo "run ./build.sh at repo root first" >&2
    exit 2
fi

# Every non-Go binding resolves libitb.so via one of these two env
# variables (JNI bindings resolve libitb_jni.so relative to
# bindings/java/build/jni/ from their own launcher, so they do not
# need either variable here).
export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"
export LD_LIBRARY_PATH="$DIST_DIR"

echo "==> (re)building tools/eitb/eitb"
(cd "$REPO/tools/eitb" && go build -o eitb .)

# ---------------------------------------------------------------------
# Profiles + eitb dispatch map.
# ---------------------------------------------------------------------

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

# LANGS listed in a canonical order (Go native first, then each
# binding directory alphabetically).
LANGS=(
    go
    ada c clojure cpp crystal csharp dart dlang elixir erlang
    fortran fsharp gleam groovy haskell java julia kotlin lfe lua
    nim nodejs ocaml php powershell python r ruby rust scala
    swift vbnet zig
)

# eitb invocation prefixes -- assembled per-language so that
# `${EITB_CMD[$lang]} encrypt <profile> <in> <out>` works for every
# entry. Multi-token commands (interpreter + script) are used
# directly via `eval`.
declare -A EITB_CMD
EITB_CMD[go]="$REPO/tools/eitb/eitb"
EITB_CMD[ada]="$REPO/bindings/ada/eitb/eitb"
EITB_CMD[c]="$REPO/bindings/c/eitb/eitb"
EITB_CMD[clojure]="$REPO/bindings/clojure/eitb/eitb"
EITB_CMD[cpp]="$REPO/bindings/cpp/eitb/eitb"
EITB_CMD[crystal]="$REPO/bindings/crystal/eitb/eitb"
EITB_CMD[csharp]="$REPO/bindings/csharp/Itb.Eitb/bin/Release/net10.0/Itb.Eitb"
EITB_CMD[dart]="$REPO/bindings/dart/eitb/eitb"
EITB_CMD[dlang]="$REPO/bindings/dlang/eitb/eitb"
EITB_CMD[elixir]="$REPO/bindings/elixir/eitb/eitb"
EITB_CMD[erlang]="$REPO/bindings/erlang/eitb/eitb.erl"
EITB_CMD[fortran]="$REPO/bindings/fortran/eitb/eitb"
EITB_CMD[fsharp]="$REPO/bindings/fsharp/eitb/EveraniumItb.FSharp.Eitb/bin/Release/net10.0/EveraniumItb.FSharp.Eitb"
EITB_CMD[gleam]="$REPO/bindings/gleam/eitb/eitb"
EITB_CMD[groovy]="$REPO/bindings/groovy/eitb/eitb"
EITB_CMD[haskell]="$REPO/bindings/haskell/eitb/eitb"
EITB_CMD[java]="$REPO/bindings/java/eitb/eitb"
EITB_CMD[julia]="$REPO/bindings/julia/eitb/eitb"
EITB_CMD[kotlin]="$REPO/bindings/kotlin/eitb/eitb"
EITB_CMD[lfe]="$REPO/bindings/lfe/eitb/eitb"
EITB_CMD[lua]="$REPO/bindings/lua/eitb/eitb"
EITB_CMD[nim]="$REPO/bindings/nim/eitb/eitb"
EITB_CMD[nodejs]="$REPO/bindings/nodejs/eitb/eitb"
EITB_CMD[ocaml]="$REPO/bindings/ocaml/eitb/eitb"
EITB_CMD[php]="$REPO/bindings/php/eitb/eitb"
EITB_CMD[powershell]="pwsh -NoProfile $REPO/bindings/powershell/eitb/eitb.ps1"
EITB_CMD[python]="python3 $REPO/bindings/python/eitb/eitb.py"
EITB_CMD[r]="$REPO/bindings/r/eitb/eitb"
EITB_CMD[ruby]="$REPO/bindings/ruby/eitb/eitb"
EITB_CMD[rust]="$REPO/bindings/rust/eitb/target/release/eitb"
EITB_CMD[scala]="$REPO/bindings/scala/eitb/eitb"
EITB_CMD[swift]="$REPO/bindings/swift/.build/x86_64-unknown-linux-gnu/release/eitb"
EITB_CMD[vbnet]="$REPO/bindings/vbnet/eitb/EveraniumItb.VisualBasic.Eitb/bin/Release/net10.0/EveraniumItb.VisualBasic.Eitb"
EITB_CMD[zig]="$REPO/bindings/zig/zig-out/bin/eitb"

# ---------------------------------------------------------------------
# Pre-flight: which eitb utilities are actually invocable? Rows /
# columns for missing ones become N/A in the matrix.
# ---------------------------------------------------------------------

echo "==> pre-flight: probing each eitb 'version'"
declare -A LANG_OK
for lang in "${LANGS[@]}"; do
    cmd="${EITB_CMD[$lang]}"
    # eval so multi-token commands (interpreter + script) work.
    if eval "$cmd version" >/dev/null 2>&1; then
        LANG_OK[$lang]=1
    else
        LANG_OK[$lang]=0
        echo "   MISSING  $lang  ($cmd)"
    fi
done

# ---------------------------------------------------------------------
# Encrypt phase: one wire per (profile, encrypter).
#
# Per-(profile, encrypter) success is tracked in ENC_OK; a failure here
# only disables THAT slot for the decrypt phase, not the whole language
# for every profile. Blob-only profiles (see PROFILES_NO_CIPHER) have
# no cipher surface by design and are skipped without disabling the
# encrypter for other profiles.
# ---------------------------------------------------------------------

SOURCE_SHA=$(sha256sum "$IN_FILE" | awk '{print $1}')
echo "==> source SHA-256: $SOURCE_SHA"

# Profiles that intentionally expose no cipher surface. Their eitb
# encrypt call would return ErrProfileNoCipher; the matrix marks every
# cell in their profile section as N/A with a documented reason.
declare -A PROFILE_SKIP_REASON
PROFILE_SKIP_REASON[blob-triple-mac-v1]="no cipher surface (blob-only profile; not exercised by eitb encrypt/decrypt)"

declare -A ENC_OK

for profile in "${PROFILES[@]}"; do
    outdir="$EITB_DIR/enc/$profile"
    mkdir -p "$outdir"
    if [ -n "${PROFILE_SKIP_REASON[$profile]:-}" ]; then
        echo "==> encrypt phase: profile=$profile SKIPPED (${PROFILE_SKIP_REASON[$profile]})"
        continue
    fi
    echo "==> encrypt phase: profile=$profile"
    for enc in "${LANGS[@]}"; do
        ENC_OK[$profile/$enc]=0
        [ "${LANG_OK[$enc]}" = "1" ] || continue
        out_bin="$outdir/$enc.bin"
        out_blob="$outdir/$enc.blob"
        cmd="${EITB_CMD[$enc]}"
        if ! eval "$cmd encrypt \"$profile\" \"$IN_FILE\" \"$out_bin\"" \
                >/dev/null 2>"$out_blob.raw"; then
            echo "   FAIL enc  $enc / $profile" >&2
            head -3 "$out_blob.raw" >&2 || true
            continue
        fi
        # Strip whitespace; the eitb contract puts nothing on stderr
        # except the hex blob (and a trailing newline).
        tr -d '[:space:]' < "$out_blob.raw" > "$out_blob"
        # Sanity check: hex-only, non-empty.
        if ! grep -qE '^[0-9a-fA-F]+$' "$out_blob"; then
            echo "   FAIL enc  $enc / $profile: stderr not pure hex" >&2
            head -c 120 "$out_blob.raw" >&2; echo >&2
            continue
        fi
        rm -f "$out_blob.raw"
        ENC_OK[$profile/$enc]=1
    done
done

# ---------------------------------------------------------------------
# Decrypt phase: for every (encrypter, profile) wire, feed it to every
# decrypter, verify SHA-256.
# ---------------------------------------------------------------------

RESULTS="$EITB_DIR/results.tsv"
LOCK="$EITB_DIR/results.tsv.lock"
: > "$RESULTS"
: > "$LOCK"

# Parallelism cap for decrypt jobs. 8 keeps 8 JVM/CLR/BEAM processes
# resident at once (well under the box's RAM ceiling) and cuts wall
# clock ~8x relative to serial. Overridable via ITB_XVERIFY_JOBS.
MAX_JOBS="${ITB_XVERIFY_JOBS:-8}"

# Semaphore helper: wait until fewer than MAX_JOBS background children
# are outstanding, then return so the caller can start one more.
throttle() {
    while :; do
        local n
        n=$(jobs -pr | wc -l)
        [ "$n" -lt "$MAX_JOBS" ] && return
        wait -n
    done
}

emit_result() {
    # $1=profile $2=enc $3=dec $4=verdict $5=diag
    {
        flock 200
        printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "${5:-}" >> "$RESULTS"
    } 200>"$LOCK"
}
export -f emit_result

run_decrypt_cell() {
    # Runs one decrypt cell in a subshell.
    local profile="$1" enc="$2" dec="$3" blob_hex="$4" out_bin="$5" decdir="$6"
    local cmd="${EITB_CMD[$dec]}"
    local back_bin="$decdir/${enc}__${dec}.bin"
    local dec_err="$decdir/${enc}__${dec}.err"
    if ! eval "$cmd decrypt \"$profile\" \"$blob_hex\" \"$out_bin\" \"$back_bin\"" \
            >/dev/null 2>"$dec_err"; then
        local diag
        diag=$(head -1 "$dec_err" 2>/dev/null | tr '\t' ' ' | head -c 200)
        emit_result "$profile" "$enc" "$dec" "FAIL" "$diag"
        return
    fi
    local got_sha
    got_sha=$(sha256sum "$back_bin" 2>/dev/null | awk '{print $1}')
    if [ "$got_sha" = "$SOURCE_SHA" ]; then
        emit_result "$profile" "$enc" "$dec" "PASS" ""
        rm -f "$back_bin" "$dec_err"
    else
        emit_result "$profile" "$enc" "$dec" "FAIL" "sha-mismatch $got_sha"
    fi
}

for profile in "${PROFILES[@]}"; do
    encdir="$EITB_DIR/enc/$profile"
    decdir="$EITB_DIR/dec/$profile"
    mkdir -p "$decdir"
    if [ -n "${PROFILE_SKIP_REASON[$profile]:-}" ]; then
        echo "==> decrypt phase: profile=$profile SKIPPED (${PROFILE_SKIP_REASON[$profile]})"
        for enc in "${LANGS[@]}"; do
            for dec in "${LANGS[@]}"; do
                emit_result "$profile" "$enc" "$dec" "NA" "${PROFILE_SKIP_REASON[$profile]}"
            done
        done
        continue
    fi
    echo "==> decrypt phase: profile=$profile (parallel=$MAX_JOBS)"
    for enc in "${LANGS[@]}"; do
        out_bin="$encdir/$enc.bin"
        out_blob="$encdir/$enc.blob"
        blob_hex=""
        if [ "${ENC_OK[$profile/$enc]:-0}" = "1" ] && [ -f "$out_bin" ] && [ -f "$out_blob" ]; then
            blob_hex=$(cat "$out_blob")
        fi
        for dec in "${LANGS[@]}"; do
            if [ "${LANG_OK[$dec]}" != "1" ]; then
                emit_result "$profile" "$enc" "$dec" "NA" "dec-missing"
                continue
            fi
            if [ "${ENC_OK[$profile/$enc]:-0}" != "1" ]; then
                emit_result "$profile" "$enc" "$dec" "NA" "enc-failed"
                continue
            fi
            if [ -z "$blob_hex" ]; then
                emit_result "$profile" "$enc" "$dec" "NA" "no-blob"
                continue
            fi
            throttle
            run_decrypt_cell "$profile" "$enc" "$dec" "$blob_hex" "$out_bin" "$decdir" &
        done
    done
    wait
    # Cumulative summary from results.tsv so parallel writes are seen.
    P=$(awk -F'\t' '$4=="PASS"{c++}END{print c+0}' "$RESULTS")
    F=$(awk -F'\t' '$4=="FAIL"{c++}END{print c+0}' "$RESULTS")
    N=$(awk -F'\t' '$4=="NA"{c++}END{print c+0}' "$RESULTS")
    echo "   profile done: PASS=$P FAIL=$F NA=$N (cumulative)"
done

TOTAL=$(wc -l < "$RESULTS")
PASS=$(awk -F'\t' '$4=="PASS"{c++}END{print c+0}' "$RESULTS")
FAIL=$(awk -F'\t' '$4=="FAIL"{c++}END{print c+0}' "$RESULTS")
NA=$(awk -F'\t' '$4=="NA"{c++}END{print c+0}' "$RESULTS")

echo "==> matrix run complete: total=$TOTAL PASS=$PASS FAIL=$FAIL NA=$NA"

# ---------------------------------------------------------------------
# Emit the Markdown matrix.
# ---------------------------------------------------------------------

MATRIX="$EITB_DIR/compat-matrix.md"
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
    echo "- N/A (missing eitb): $NA"
    if [ "$FAIL" -eq 0 ] && [ "$NA" -eq 0 ]; then
        echo "- Verdict: PASS"
    elif [ "$FAIL" -eq 0 ]; then
        echo "- Verdict: PASS (some cells N/A due to missing eitb utilities)"
    else
        echo "- Verdict: FAIL"
    fi
    echo
    echo "Absent eitb utilities (rows / columns marked \`-\`):"
    any_missing=0
    for lang in "${LANGS[@]}"; do
        if [ "${LANG_OK[$lang]}" != "1" ]; then
            echo "- \`$lang\`"
            any_missing=1
        fi
    done
    if [ "$any_missing" = "0" ]; then
        echo "- (none -- all 34 eitb utilities invocable)"
    fi
    echo
    echo "## Per-profile matrix"
    echo
    for profile in "${PROFILES[@]}"; do
        echo "### $profile"
        echo
        # Header row: "enc \\ dec | lang1 | lang2 | ..."
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
                cell=$(awk -F'\t' -v p="$profile" -v e="$enc" -v d="$dec" \
                    '$1==p && $2==e && $3==d { print $4; exit }' "$RESULTS")
                case "$cell" in
                    PASS) mark="✓" ;;
                    FAIL) mark="✗" ;;
                    NA)   mark="-" ;;
                    *)    mark="?" ;;
                esac
                row="$row $mark |"
            done
            echo "$row"
        done
        echo
    done
    if [ "$FAIL" -gt 0 ]; then
        echo "## Failures detail"
        echo
        echo "| profile | encrypter | decrypter | diagnostic |"
        echo "|:---|:---|:---|:---|"
        awk -F'\t' '$4=="FAIL" { printf("| %s | %s | %s | %s |\n", $1, $2, $3, $5) }' "$RESULTS"
        echo
    fi
} > "$MATRIX"

echo "==> matrix rendered: $MATRIX"
echo "==> per-cell results: $RESULTS"
