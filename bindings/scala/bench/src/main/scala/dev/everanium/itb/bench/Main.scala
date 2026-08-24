// Bench entry: `message`, `stream`, or `all` (default).

package dev.everanium.itb.bench

import dev.everanium.itb.Runtime

object Main:

  def main(args: Array[String]): Unit =
    // Go-runtime pacing caps for bench-scale allocation churn; the
    // run_bench.sh env defaults apply the same values at load time —
    // the programmatic setter wins when both are present.
    val _ = Runtime.setMemoryLimit(512L * 1024 * 1024)
    val _ = Runtime.setGCPercent(20)
    args.headOption.getOrElse("all") match
      case "message" => BenchMessage.run()
      case "stream"  => BenchStream.run()
      case "all" =>
        BenchMessage.run()
        BenchStream.run()
      case other =>
        System.err.println(s"usage: bench [message|stream|all] (got: $other)")
        sys.exit(2)
