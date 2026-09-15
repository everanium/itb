// swift-tools-version: 6.0
//
// Package.swift — SwiftPM manifest for the ITB Swift binding.
//
// The manifest lives at the repository root because SwiftPM resolves a
// dependency only from a repository whose root carries Package.swift —
// `.package(url:)` has no subdirectory parameter. The binding's sources
// stay under bindings/swift/ and are reached through each target's
// `path:`.
//
// The binding is a thin proxy over the C binding's public surface
// (bindings/c/include/itb3.h, libitb3_c) which in turn links the
// libitb3 shared library (cmd/cshared). Both native libraries are
// resolved at compile time with embedded RPATHs — no runtime symbol
// loading. Build bindings/c first (bindings/swift/build.sh does both
// steps).

import PackageDescription
import Foundation

// Absolute paths derived from the manifest location so the link +
// rpath flags stay machine-independent inside the repository.
let repoRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let bindingsDir = repoRoot.appendingPathComponent("bindings")
let cBuildDir = bindingsDir.appendingPathComponent("c/build").path
let distDir = repoRoot.appendingPathComponent("dist/linux-amd64").path

// The Swift binding's sources, relative to the repository root.
let swiftDir = "bindings/swift"

// libitb3_c.so carries its own RPATH to dist/, but both directories are
// embedded here so the produced binaries run from any working
// directory without LD_LIBRARY_PATH.
let itbLinkerSettings: [LinkerSetting] = [
    .linkedLibrary("itb3_c"),
    .linkedLibrary("itb3"),
    .unsafeFlags([
        "-L\(cBuildDir)",
        "-L\(distDir)",
        "-Xlinker", "-rpath", "-Xlinker", cBuildDir,
        "-Xlinker", "-rpath", "-Xlinker", distDir,
    ]),
]

let package = Package(
    name: "LibItb3",
    products: [
        .library(name: "LibItb3", targets: ["Itb3"]),
        .executable(name: "Itb3Bench", targets: ["Itb3Bench"]),
        .executable(name: "eitb", targets: ["eitb"]),
    ],
    targets: [
        .systemLibrary(name: "CItb", path: "\(swiftDir)/Sources/CItb"),
        .target(
            name: "Itb3",
            dependencies: ["CItb"],
            path: "\(swiftDir)/Sources/Itb3",
            linkerSettings: itbLinkerSettings
        ),
        .executableTarget(
            name: "Itb3Bench",
            dependencies: ["Itb3"],
            path: "\(swiftDir)/Sources/Itb3Bench"
        ),
        .executableTarget(
            name: "eitb",
            dependencies: ["Itb3"],
            path: "\(swiftDir)/Sources/eitb"
        ),
        .testTarget(
            name: "Itb3Tests",
            dependencies: ["Itb3"],
            path: "\(swiftDir)/Tests/Itb3Tests"
        ),
    ]
)
