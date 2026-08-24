#!/usr/bin/env bash
#
# build.sh -- one-step build for the PHP binding's libitb.so
# dependency. Prerequisites (Go, PHP 7.4+ with the FFI extension
# available) must be installed separately; see README.md
# "Prerequisites" section.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm
#                          # (use on hosts without AVX-512+VL)

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

cd "$REPO_ROOT"
echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared

cd "$REPO_ROOT/bindings/php"
echo "==> lint-checking the PHP sources"
find src tests bench eitb -name '*.php' -print0 | while IFS= read -r -d '' f; do
    php -l "$f" > /dev/null
done
php -l autoload.php > /dev/null

echo "==> PHP binding loads libitb.so at runtime via FFI; no further build step."
echo "==> ready: ./run_tests.sh"
