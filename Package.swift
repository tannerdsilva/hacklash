// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "hacklash",
	platforms:[
		.macOS(.v14)
	],
	products: [
		.library(name:"wireguard-userspace-nio", targets:["wireguard-userspace-nio"]),
	],
	dependencies: [
		.package(path:"../rawdog"),
		// .package(url:"https://github.com/tannerdsilva/rawdog.git", branch:"hacklash"),
		.package(url:"https://github.com/apple/swift-nio.git", "2.50.0"..<"3.0.0"),
		.package(url:"https://github.com/apple/swift-service-lifecycle.git", "2.4.0"..<"3.0.0"),
		.package(url:"https://github.com/tannerdsilva/ws-kit.git", branch:"hacklash"),
		.package(url:"https://github.com/apple/swift-log.git", "1.0.0"..<"2.0.0"),
		// .package(url:"https://github.com/tannerdsilva/bedrock.git", branch:"hacklash")
		.package(path:"../bedrock")
	],
    targets: [
		.target(
			name:"wireguard-userspace-nio",
			dependencies: [
				.product(name:"RAW", package:"rawdog"),
				.product(name:"RAW_dh25519", package:"rawdog"),
				.product(name:"RAW_chachapoly", package:"rawdog"),
				.product(name:"NIO", package:"swift-nio"),
				.product(name:"bedrock", package:"bedrock"),
				.product(name:"RAW_xchachapoly", package:"rawdog"),
				.product(name:"RAW_blake2", package:"rawdog"),
				.product(name:"RAW_hmac", package:"rawdog"),
				.product(name:"ServiceLifecycle", package:"swift-service-lifecycle"),
				.product(name:"WebCore", package:"ws-kit"),
			]
		),
		.executableTarget(name:"hacklash", dependencies:[
			"wireguard-userspace-nio",
			.product(name:"NIO", package:"swift-nio"),
		])
    ]
)
