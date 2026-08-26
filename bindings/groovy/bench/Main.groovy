// Bench entry: `message`, `stream`, or `all` (default).

package dev.everanium.itb.groovy.bench

import groovy.transform.CompileStatic

import dev.everanium.itb.groovy.Runtime

@CompileStatic
final class Main {

    private Main() {
    }

    static void main(String[] args) {
        // Go-runtime pacing caps for bench-scale allocation churn;
        // the run_bench.sh env defaults apply the same values at
        // load time — the programmatic setter wins when both are
        // present.
        Runtime.setMemoryLimit(512L * 1024 * 1024)
        Runtime.setGCPercent(20)
        String shape = args.length > 0 ? args[0] : 'all'
        switch (shape) {
            case 'message':
                BenchMessage.run()
                break
            case 'stream':
                BenchStream.run()
                break
            case 'stream_one_shot':
                BenchStreamOneShot.run()
                break
            case 'all':
                BenchMessage.run()
                BenchStream.run()
                BenchStreamOneShot.run()
                break
            default:
                System.err.println(
                    "usage: bench [message|stream|stream_one_shot|all] (got: $shape)")
                System.exit(2)
        }
    }
}
