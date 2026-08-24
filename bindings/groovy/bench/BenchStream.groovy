// Stream-pump throughput vs plaintext size (Streaming Non-AEAD
// profile) at 1 MiB / 16 MiB / 64 MiB.

package dev.everanium.itb.groovy.bench

import groovy.transform.CompileStatic

import dev.everanium.itb.groovy.Pipeline

@CompileStatic
final class BenchStream {

    private BenchStream() {
    }

    static void run() {
        String profile = BenchUtil.profileName('streaming-noaead-triple-v1')
        Pipeline.withPipeline(profile, BenchUtil.buildOpts()) { Pipeline pipe ->
            BenchUtil.header()
            BenchUtil.SIZES.each { int size ->
                byte[] plain = BenchUtil.payload(size)
                BenchUtil.benchCase('stream_pump', size) {
                    def wire = new ByteArrayOutputStream(size + size.intdiv(4) + 131_072)
                    pipe.encryptStreamPump(new ByteArrayInputStream(plain), wire)
                }
            }
        }
    }
}
