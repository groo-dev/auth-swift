// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "GrooAuth",
    platforms: [.iOS(.v18), .macOS(.v14)],
    products: [
        .library(name: "GrooAuth", targets: ["GrooAuth"]),
        // A SEPARATE product, deliberately. `gr/ios`'s AutoFill extension links
        // GrooAuth to call accessToken() and has no UI of its own; folding SwiftUI
        // into that target would make every app extension carry a UI library it
        // never renders.
        .library(name: "GrooAuthUI", targets: ["GrooAuthUI"]),
    ],
    targets: [
        .target(name: "GrooAuth"),
        .target(name: "GrooAuthUI", dependencies: ["GrooAuth"]),
        .testTarget(name: "GrooAuthTests", dependencies: ["GrooAuth"]),
        .testTarget(name: "GrooAuthUITests", dependencies: ["GrooAuthUI"]),
    ]
)
