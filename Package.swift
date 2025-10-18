// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "OttoCryptSwift",
    platforms: [
        .iOS(.v14), .macOS(.v12)
    ],
    products: [
        .library(name: "IvanSostarkoOttoCrypt", targets: ["IvanSostarkoOttoCrypt"]),
    ],
    dependencies: [
        // Swift-Sodium brings in libsodium and the C module 'Clibsodium'
        .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.2")
    ],
    targets: [
        .target(
            name: "IvanSostarkoOttoCrypt",
            dependencies: [
                .product(name: "Clibsodium", package: "swift-sodium")
            ]
        ),
        .testTarget(
            name: "IvanSostarkoOttoCryptTests",
            dependencies: ["IvanSostarkoOttoCrypt"]
        )
    ]
)
