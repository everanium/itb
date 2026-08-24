/*
 * ErrorsTests.swift — error-mapping surface: opaque-string relay,
 * profile registration with an 8-entry `innerHashes` constellation,
 * duplicate registration, and the mapped status codes.
 */

import Foundation
import XCTest
@testable import Itb

final class ErrorsTests: XCTestCase {
    func testUnknownProfile() {
        XCTAssertThrowsError(try Pipeline(profile: "no-such-profile")) { error in
            guard let err = error as? ItbError else {
                return XCTFail("not an ItbError: \(error)")
            }
            XCTAssertEqual(err.status, .badInput)
            XCTAssertFalse(err.message.isEmpty, "diagnostic must be non-empty")
        }
    }

    func testUnknownOptsKey() throws {
        // Typoed lowercase s — rejected Go-side, not by the binding.
        let bad = try Opts().set("chunksize", "4096")
        XCTAssertThrowsError(
            try Pipeline(profile: "singlemsg-triple-mac-v1", opts: bad)
        ) { error in
            XCTAssertEqual((error as? ItbError)?.status, .badInput)
        }
    }

    func testUnknownInnerHash() throws {
        // An unknown inner-hash name is relayed to Go and rejected
        // there — the binding performs no name validation of its own.
        let hash = try Opts().set("innerHash", "no-such-hash")
        XCTAssertThrowsError(
            try Pipeline(profile: "singlemsg-triple-mac-v1", opts: hash))
    }

    func testRegisterProfileAndDuplicate() throws {
        let reg = try Opts()
        try reg.set("mode", "singlemsg-nomac")
        try reg.set("width", "256")
        try reg.set("innerHashes",
                    "blake3,blake2s,areion256,blake2b256,"
                        + "chacha20,blake3,blake2s,areion256")
        try reg.set("keyBits", "1024")
        try reg.set("parallaxOn", "false")
        try reg.set("wrapperOn", "false")
        try registerProfile(name: "swift-binding-test-mixed", opts: reg)

        // The registered profile round-trips.
        let sender = try Pipeline(profile: "swift-binding-test-mixed")
        let receiver = try Pipeline(open: "swift-binding-test-mixed",
                                    blob: sender.blob)
        let plain = Data("custom profile".utf8)
        let back = try receiver.decryptMessage(try sender.encryptMessage(plain))
        XCTAssertEqual(back, plain)

        // Duplicate name is a distinct status.
        XCTAssertThrowsError(
            try registerProfile(name: "swift-binding-test-mixed", opts: reg)
        ) { error in
            XCTAssertEqual((error as? ItbError)?.status, .profileExists)
        }
    }

    func testStatusLabels() {
        XCTAssertFalse(Status.ok.label.isEmpty)
        XCTAssertFalse(Status.macFailure.label.isEmpty)
        XCTAssertFalse(Status.internalError.label.isEmpty)
    }

    func testFreedStreamRejectsUse() throws {
        let pipe = try Pipeline(profile: "streaming-aead-triple-mac-v1")
        let session = try pipe.encryptStream()
        session.free()
        session.free() // idempotent
        XCTAssertThrowsError(try session.write(Data([1, 2, 3]))) { error in
            XCTAssertEqual((error as? ItbError)?.status, .badInput)
        }
    }
}
