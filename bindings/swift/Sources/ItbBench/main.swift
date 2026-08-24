/*
 * main.swift — bench driver: `ItbBench [message|stream|all]`.
 *
 * Bench-scale allocation churn leaks Go scratch heap unboundedly
 * without a soft memory cap + aggressive GC; the setters report the
 * previous values, not an error.
 */

import Foundation
import Itb

ItbRuntime.setMemoryLimit(512 << 20) // 512 MiB soft cap
ItbRuntime.setGCPercent(20)          // aggressive GC

let mode = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "all"
switch mode {
case "message":
    benchHeader()
    runMessageBench()
case "stream":
    benchHeader()
    runStreamBench()
case "all":
    benchHeader()
    runMessageBench()
    runStreamBench()
default:
    FileHandle.standardError.write(
        Data("usage: ItbBench [message|stream|all]\n".utf8))
    exit(2)
}
