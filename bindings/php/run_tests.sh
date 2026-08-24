#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the PHP binding.
# Builds libitb.so via build.sh, points ITB_LIBITB_PATH at the
# freshly-built shared library, then invokes PHPUnit against the
# tests/ tree. Positional arguments are forwarded to PHPUnit (e.g.
# --filter MessageTest).
#
# PHPUnit resolution order:
#   1. $ITB_PHPUNIT (path to a phpunit executable or .phar)
#   2. phpunit on PATH
#   3. vendor/bin/phpunit (composer install --dev)
#   4. tools/phpunit.phar
#
# Usage:
#   ./run_tests.sh                       # full suite
#   ./run_tests.sh --filter StreamTest   # one class

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"

PHPUNIT=""
if [[ -n "${ITB_PHPUNIT:-}" ]]; then
    PHPUNIT="$ITB_PHPUNIT"
elif command -v phpunit > /dev/null 2>&1; then
    PHPUNIT="$(command -v phpunit)"
elif [[ -x vendor/bin/phpunit ]]; then
    PHPUNIT="vendor/bin/phpunit"
elif [[ -f tools/phpunit.phar ]]; then
    PHPUNIT="tools/phpunit.phar"
else
    echo "run_tests.sh: PHPUnit not found." >&2
    echo "Install one of:" >&2
    echo "  composer install                                     # vendor/bin/phpunit" >&2
    echo "  sudo pacman -S phpunit                               # PATH" >&2
    echo "  curl -sSLo tools/phpunit.phar https://phar.phpunit.de/phpunit-12.phar" >&2
    echo "or point ITB_PHPUNIT at an existing executable / phar." >&2
    exit 1
fi

PHP_ARGS=()
if ! php -m 2>/dev/null | grep -qix ffi; then
    PHP_ARGS+=(-d extension=ffi)
fi
PHP_ARGS+=(-d ffi.enable=1)

exec php "${PHP_ARGS[@]}" "$PHPUNIT" --bootstrap autoload.php --colors=auto "$@" tests
