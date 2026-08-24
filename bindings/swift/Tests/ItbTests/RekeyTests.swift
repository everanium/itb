/*
 * RekeyTests.swift — Init → rekey → Open receiver with the rotated
 * blob → round trip.
 */

import Foundation
import XCTest
@testable import Itb

final class RekeyTests: XCTestCase {
    func testRekeyRefreshesBlobAndRoundTrips() throws {
        let sender = try Pipeline(profile: "singlemsg-triple-mac-v1")
        let before = sender.blob

        let perm = Data(repeating: 0x11, count: 32)
        let wrap = Data(repeating: 0x22, count: 32)
        try sender.rekey(permMaster: perm, wrapMaster: wrap)
        XCTAssertNotEqual(sender.blob, before, "rekey must refresh the blob")

        let receiver = try Pipeline(open: "singlemsg-triple-mac-v1",
                                    blob: sender.blob)
        let plain = testPayload(32768, seed: 0xBEEF)
        let wire = try sender.encryptMessage(plain)
        let back = try receiver.decryptMessage(wire)
        XCTAssertEqual(back, plain)
    }
}
