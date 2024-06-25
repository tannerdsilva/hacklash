// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "hacklash",
	platforms:[
		.macOS(.v12)
	],
	products: [
		.library(name:"wireguard-userspace", targets:["wireguard-userspace"]),
	],
	dependencies: [
		.package(path:"../rawdog"),
		// .package(url:"https://github.com/tannerdsilva/rawdog.git", branch:"hacklash"),
		.package(url:"https://github.com/apple/swift-nio.git", "2.50.0"..<"3.0.0"),
		// .package(url:"https://github.com/tannerdsilva/bedrock.git", branch:"hacklash")
		.package(path:"../bedrock")
	],
    targets: [
		.target(
			name:"wireguard-userspace",
			dependencies: [
				.product(name:"RAW", package:"rawdog"),
				.product(name:"RAW_dh25519", package:"rawdog"),
				.product(name:"RAW_chachapoly", package:"rawdog"),
				.product(name:"NIO", package:"swift-nio"),
				.product(name:"bedrock", package:"bedrock"),
				.product(name:"RAW_xchachapoly", package:"rawdog"),
				.product(name:"RAW_blake2", package:"rawdog"),
				.product(name:"RAW_hmac", package:"rawdog"),
			]
		),
		.executableTarget(name:"hacklash", dependencies:[
			"wireguard-userspace",
			.product(name:"NIO", package:"swift-nio"),
		])
    ]
)
