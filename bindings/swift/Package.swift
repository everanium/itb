// swift-tools-version: 6.0
//
// Package.swift — SwiftPM manifest for the ITB Swift binding.
//
// The binding is a thin proxy over the C binding's public surface
// (bindings/c/include/itb.h, libitb_c) which in turn links the
// libitb shared library (cmd/cshared). Both native libraries are
// resolved at compile time with embedded RPATHs — no runtime symbol
// loading. Build bindings/c first (./build.sh does both steps).

import PackageDescription
import Foundation

// Absolute paths derived from the manifest location so the link +
// rpath flags stay machine-independent inside the repository.
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let bindingsDir = packageDir.deletingLastPathComponent()
let repoRoot = bindingsDir.deletingLastPathComponent()
let cBuildDir = bindingsDir.appendingPathComponent("c/build").path
let distDir = repoRoot.appendingPathComponent("dist/linux-amd64").path

// libitb_c.so carries its own RPATH to dist/, but both directories are
// embedded here so the produced binaries run from any working
// directory without LD_LIBRARY_PATH.
let itbLinkerSettings: [LinkerSetting] = [
    .linkedLibrary("itb_c"),
    .linkedLibrary("itb"),
    .unsafeFlags([
        "-L\(cBuildDir)",
        "-L\(distDir)",
        "-Xlinker", "-rpath", "-Xlinker", cBuildDir,
        "-Xlinker", "-rpath", "-Xlinker", distDir,
    ]),
]

let package = Package(
    name: "Itb",
    products: [
        .library(name: "Itb", targets: ["Itb"]),
        .executable(name: "ItbBench", targets: ["ItbBench"]),
        .executable(name: "eitb", targets: ["eitb"]),
    ],
    targets: [
        .systemLibrary(name: "CItb", path: "Sources/CItb"),
        .target(
            name: "Itb",
            dependencies: ["CItb"],
            linkerSettings: itbLinkerSettings
        ),
        .executableTarget(name: "ItbBench", dependencies: ["Itb"]),
        .executableTarget(name: "eitb", dependencies: ["Itb"]),
        .testTarget(name: "ItbTests", dependencies: ["Itb"]),
    ]
)
