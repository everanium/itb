// Stream-pump throughput vs plaintext size (Streaming Non-AEAD
// profile) at 1 MiB / 16 MiB / 64 MiB.

package com.everanium.itb.kotlin.bench

import com.everanium.itb.kotlin.Pipeline
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

internal object BenchStream {

    fun run() {
        Pipeline.init(
            BenchUtil.profileName("streaming-noaead-triple-v1"), BenchUtil.buildOpts(),
        ).use { pipe ->
            BenchUtil.header()
            for (size in BenchUtil.sizes) {
                val plain = ByteArray(size)
                BenchUtil.csprngFill(plain)
                BenchUtil.case("stream_pump", size) {
                    val wire = ByteArrayOutputStream(size + size / 4 + 131_072)
                    pipe.encryptStreamPump(ByteArrayInputStream(plain), wire)
                }
                // Pre-encrypt one wire outside the decrypt timing loop.
                val setupWire = ByteArrayOutputStream(size + size / 4 + 131_072)
                pipe.encryptStreamPump(ByteArrayInputStream(plain), setupWire)
                val decWire = setupWire.toByteArray()
                BenchUtil.case("stream_pump-dec", size) {
                    val out = ByteArrayOutputStream(size + 131_072)
                    pipe.decryptStreamPump(ByteArrayInputStream(decWire), out)
                }
            }
        }
    }
}
