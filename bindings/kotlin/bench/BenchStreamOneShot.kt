// Whole-buffer Stream throughput vs plaintext size (Streaming
// Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Times
// encryptStreamOneShot / decryptStreamOneShot, the single FFI
// round-trip surface for callers holding the whole payload in
// memory.

package com.everanium.itb.kotlin.bench

import com.everanium.itb.kotlin.Pipeline

internal object BenchStreamOneShot {

    fun run() {
        Pipeline.init(
            BenchUtil.profileName("streaming-noaead-triple-v1"), BenchUtil.buildOpts(),
        ).use { pipe ->
            BenchUtil.header()
            for (size in BenchUtil.sizes) {
                val plain = ByteArray(size)
                BenchUtil.csprngFill(plain)
                BenchUtil.case("stream_one_shot", size) {
                    pipe.encryptStreamOneShot(plain)
                }
                // Pre-encrypt one wire outside the decrypt timing loop.
                val decWire = pipe.encryptStreamOneShot(plain)
                BenchUtil.case("stream_one_shot-dec", size) {
                    pipe.decryptStreamOneShot(decWire)
                }
            }
        }
    }
}
