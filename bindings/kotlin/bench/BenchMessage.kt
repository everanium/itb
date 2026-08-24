// encryptMessage throughput vs plaintext size (Single Message
// profile) at 1 MiB / 16 MiB / 64 MiB.

package com.everanium.itb.kotlin.bench

import com.everanium.itb.kotlin.Pipeline

internal object BenchMessage {

    fun run() {
        Pipeline.init(
            BenchUtil.profileName("singlemsg-triple-nomac-v1"), BenchUtil.buildOpts(),
        ).use { pipe ->
            BenchUtil.header()
            for (size in BenchUtil.sizes) {
                val plain = ByteArray(size)
                BenchUtil.csprngFill(plain)
                BenchUtil.case("message", size) { pipe.encryptMessage(plain) }
            }
        }
    }
}
