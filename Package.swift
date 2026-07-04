// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "GrooAuth",
    platforms: [.iOS(.v18), .macOS(.v14)],
    products: [.library(name: "GrooAuth", targets: ["GrooAuth"])],
    targets: [
        .target(name: "GrooAuth"),
        .testTarget(name: "GrooAuthTests", dependencies: ["GrooAuth"]),
    ]
)
