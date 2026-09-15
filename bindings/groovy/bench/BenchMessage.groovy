// encryptMessage throughput vs plaintext size (Single Message
// profile) at 1 MiB / 16 MiB / 64 MiB.

package io.github.everanium.itb3.groovy.bench

import groovy.transform.CompileStatic

import io.github.everanium.itb3.groovy.Pipeline

@CompileStatic
final class BenchMessage {

    private BenchMessage() {
    }

    static void run() {
        String profile = BenchUtil.profileName('singlemsg-triple-nomac-v1')
        Pipeline.withPipeline(profile, BenchUtil.buildOpts()) { Pipeline pipe ->
            BenchUtil.header()
            BenchUtil.SIZES.each { int size ->
                byte[] plain = BenchUtil.payload(size)
                BenchUtil.benchCase('message', size) {
                    pipe.encryptMessage(plain)
                }
                // Pre-encrypt one wire outside the decrypt timing loop.
                byte[] decWire = pipe.encryptMessage(plain)
                BenchUtil.benchCase('message-dec', size) {
                    pipe.decryptMessage(decWire)
                }
            }
        }
    }
}
