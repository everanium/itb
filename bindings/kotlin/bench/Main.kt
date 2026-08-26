// Bench entry point: `message`, `stream`, or `all` (default).

package com.everanium.itb.kotlin.bench

import com.everanium.itb.kotlin.ItbRuntime
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    // Go-runtime pacing caps for bench-scale allocation churn;
    // run_bench.sh exports the same defaults via ITB_GOMEMLIMIT /
    // ITB_GOGC as a fallback.
    ItbRuntime.setMemoryLimit(512L shl 20)
    ItbRuntime.setGCPercent(20)

    when (args.firstOrNull() ?: "all") {
        "message" -> BenchMessage.run()
        "stream" -> BenchStream.run()
        "stream_one_shot" -> BenchStreamOneShot.run()
        "all" -> {
            BenchMessage.run()
            BenchStream.run()
            BenchStreamOneShot.run()
        }
        else -> {
            System.err.println("usage: bench [message|stream|stream_one_shot|all]")
            exitProcess(2)
        }
    }
}
