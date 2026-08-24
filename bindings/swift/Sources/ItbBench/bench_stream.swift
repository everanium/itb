/*
 * bench_stream.swift — encryptStreamPump throughput vs plaintext
 * size (streaming Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB.
 */

import Foundation
import Itb

func runStreamBench() {
    do {
        let opts = try benchBuildOpts()
        let pipe = try Pipeline(profile: benchProfileName("streaming-noaead-triple-v1"),
                                opts: opts)
        for size in [1 << 20, 16 << 20, 64 << 20] {
            let plain = benchPayload(size)
            benchCase("stream_pump", size) {
                _ = try pipe.encryptStreamPump(plain)
            }
        }
    } catch {
        FileHandle.standardError.write(
            Data("bench_stream: init failed: \(error)\n".utf8))
        exit(1)
    }
}
