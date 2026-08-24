#!/usr/bin/env bash
#
# build.sh -- one-step build for the LFE binding. Chains the Erlang
# binding's build.sh (libitb.so + the C binding's static archive +
# the NIF shim) and then compiles the rebar3 project; rebar3
# rebuilds the Erlang application as a checkout dependency
# (_checkouts/itb -> ../erlang). Prerequisites (Go, a C11 compiler,
# GNU make, Erlang/OTP 27+, rebar3) must be installed separately;
# the LFE compiler arrives as a hex dependency, so no system LFE
# install is required. See README.md "Prerequisites".
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm
#   CC=clang ./build.sh    # override the C compiler

set -eu
set -o pipefail

cd "$(dirname "$0")"

../erlang/build.sh "$@"

echo "==> rebar3 compile (LFE sources via the rebar3_lfe plugin)"
rebar3 compile

echo "==> ready: ./run_tests.sh"
