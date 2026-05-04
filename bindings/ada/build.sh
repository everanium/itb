#!/usr/bin/env bash
#
# build.sh -- one-step build for the Ada binding: libitb.so +
# gprbuild on the library project (and tests / benches via the
# extra positional argument). Prerequisites (Go, gcc-ada, Alire +
# alr toolchain --select for gnat_native + gprbuild) must be
# installed separately; see README.md "Prerequisites" section.
#
# Usage:
#   ./build.sh                                   # libitb.so + library
#   ./build.sh --noitbasm                        # ditto, with ITB asm off
#   ./build.sh --skip-libitb                     # skip the Go libitb.so step
#   ./build.sh -- -P itb_tests.gpr               # forward args to gprbuild
#   ./build.sh --noitbasm -- -P itb_tests.gpr -f # forced rebuild of tests
#
# A wrapper around `alr exec -- gprbuild` that filters the cosmetic
# ".sframe" linker notice (cf. README.md and itb.gpr Linker comment).
# The notice is emitted by the Alire-bundled binutils 2.40+ when it
# meets a system glibc Scrt1.o whose .sframe section is in an older
# format; the binary is produced correctly regardless. The grep
# pattern is permissive (matches "Scrt1.o" + ".sframe" co-occurring)
# so lines corrupted by parallel-ld interleaved writes are caught.

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

# --- argument parsing -------------------------------------------------

SKIP_LIBITB=0
TAGS=()
GPR_ARGS=()

while [ "${1:-}" != "" ]; do
    case "$1" in
        --noitbasm)    TAGS=(-tags=noitbasm); shift;;
        --skip-libitb) SKIP_LIBITB=1; shift;;
        -h|--help)
            sed -n '4,18p' "$0"
            exit 0
            ;;
        --)
            shift
            GPR_ARGS=("$@")
            break
            ;;
        *)
            echo "unknown option: $1 (use '--' to forward args to gprbuild)" >&2
            exit 2
            ;;
    esac
done

# Default gprbuild target: the library project.
if [ "${#GPR_ARGS[@]}" -eq 0 ]; then
    GPR_ARGS=(-P itb.gpr)
fi

# --- libitb.so step ---------------------------------------------------

if [ "$SKIP_LIBITB" -eq 0 ]; then
    cd "$REPO_ROOT"
    echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
    go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
        -o dist/linux-amd64/libitb.so ./cmd/cshared
fi

# --- gprbuild step ----------------------------------------------------

cd "$REPO_ROOT/bindings/ada"
echo "==> gprbuild ${GPR_ARGS[*]}"

# Merge stdout + stderr into one stream and filter through grep -v
# to strip the cosmetic .sframe notice. The pattern catches lines
# corrupted by parallel-ld interleaved writes (when Builder uses -j0
# / multi-job link). PIPESTATUS[0] preserves gprbuild's exit code
# through the pipe.
alr exec -- gprbuild "${GPR_ARGS[@]}" 2>&1 \
    | grep -vE 'Scrt1\.o.*\.sframe|\.sframe.*Scrt1\.o' || true
exit "${PIPESTATUS[0]}"
