// Whole-buffer Stream throughput vs plaintext size (Streaming
// Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Times
// encryptStreamOneShot / decryptStreamOneShot, the single FFI
// round-trip surface for callers holding the whole payload in
// memory.

package io.github.everanium.itb3.groovy.bench

import groovy.transform.CompileStatic

import io.github.everanium.itb3.groovy.Pipeline

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
