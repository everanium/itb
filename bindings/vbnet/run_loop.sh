#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the VB.NET binding:
# builds the utility with dotnet (a no-op when it is up to date;
# libitb3.so and the binding assemblies are assumed built by build.sh)
# and execs it with every argument passed through.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

dotnet build loop/Everanium.LibItb3.VisualBasic.Loop.vbproj -c Release --nologo -v quiet >/dev/null

ARTIFACT=(loop/bin/Release/net*/Everanium.LibItb3.VisualBasic.Loop)
if [ "${#ARTIFACT[@]}" -ne 1 ] || [ ! -x "${ARTIFACT[0]}" ]; then
    echo "run_loop.sh: expected exactly one loop executable, found ${#ARTIFACT[@]}" >&2
    exit 1
fi

exec "${ARTIFACT[0]}" "$@"
