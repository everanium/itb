// Whole-buffer Stream throughput vs plaintext size (Streaming
// Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Times
// encryptStreamOneShot / decryptStreamOneShot, the single FFI
// round-trip surface for callers holding the whole payload in
// memory.

package dev.everanium.itb.bench

import scala.util.Using

import dev.everanium.itb.Pipeline

object BenchStreamOneShot:

  def run(): Unit =
    val profile = BenchUtil.profileName("streaming-noaead-triple-v1")
    Using.resource(
      Pipeline.init(profile, BenchUtil.buildOpts).fold(e => throw e, identity)
    ) { pipe =>
      BenchUtil.header()
      for size <- BenchUtil.Sizes do
        val plain = BenchUtil.payload(size)
        BenchUtil.benchCase("stream_one_shot", size) {
          pipe.encryptStreamOneShot(plain).fold(e => throw e, _ => ())
        }
        // Pre-encrypt one wire outside the decrypt timing loop.
        val decWire = pipe.encryptStreamOneShot(plain).fold(e => throw e, identity)
        BenchUtil.benchCase("stream_one_shot-dec", size) {
          pipe.decryptStreamOneShot(decWire).fold(e => throw e, _ => ())
        }
    }
