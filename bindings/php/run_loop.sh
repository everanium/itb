#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the PHP binding:
# runs the utility with every argument passed through. The utility is
# pure PHP over the binding's FFI bridge, so there is nothing to
# compile here; build.sh owns libitb3.so and the lint check over the
# sources.
#
# The FFI extension is enabled for the invocation when the host PHP
# does not load it by default, exactly as the eitb launcher does.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

PHP_ARGS=()
if ! php -m 2>/dev/null | grep -qix ffi; then
    PHP_ARGS+=(-d extension=ffi)
fi
PHP_ARGS+=(-d ffi.enable=1)

exec php "${PHP_ARGS[@]}" loop/main.php "$@"
