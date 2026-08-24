// encryptMessage throughput vs plaintext size (Single Message
// profile) at 1 MiB / 16 MiB / 64 MiB.

package dev.everanium.itb.bench

import scala.util.Using

import dev.everanium.itb.Pipeline

object BenchMessage:

  def run(): Unit =
    val profile = BenchUtil.profileName("singlemsg-triple-nomac-v1")
    Using.resource(
      Pipeline.init(profile, BenchUtil.buildOpts).fold(e => throw e, identity)
    ) { pipe =>
      BenchUtil.header()
      for size <- BenchUtil.Sizes do
        val plain = BenchUtil.payload(size)
        BenchUtil.benchCase("message", size) {
          pipe.encryptMessage(plain).fold(e => throw e, _ => ())
        }
    }
