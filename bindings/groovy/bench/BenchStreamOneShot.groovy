// Whole-buffer Stream throughput vs plaintext size (Streaming
// Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Times
// encryptStreamOneShot / decryptStreamOneShot, the single FFI
// round-trip surface for callers holding the whole payload in
// memory.

package dev.everanium.itb.groovy.bench

import groovy.transform.CompileStatic

import dev.everanium.itb.groovy.Pipeline

@CompileStatic
final class BenchStreamOneShot {

    private BenchStreamOneShot() {
    }

    static void run() {
        String profile = BenchUtil.profileName('streaming-noaead-triple-v1')
        Pipeline.withPipeline(profile, BenchUtil.buildOpts()) { Pipeline pipe ->
            BenchUtil.header()
            BenchUtil.SIZES.each { int size ->
                byte[] plain = BenchUtil.payload(size)
                BenchUtil.benchCase('stream_one_shot', size) {
                    pipe.encryptStreamOneShot(plain)
                }
                // Pre-encrypt one wire outside the decrypt timing loop.
                byte[] decWire = pipe.encryptStreamOneShot(plain)
                BenchUtil.benchCase('stream_one_shot-dec', size) {
                    pipe.decryptStreamOneShot(decWire)
                }
            }
        }
    }
}
