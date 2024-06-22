// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

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
		.package(url:"https://github.com/tannerdsilva/rawdog.git", branch:"hacklash"),
		.package(url:"https://github.com/apple/swift-nio.git", "2.50.0"..<"3.0.0"),
	],
    targets: [
		.target(
			name:"wireguard-userspace",
			dependencies: [
				.product(name:"RAW", package:"rawdog"),
				.product(name:"NIO", package:"swift-nio"),
			]
		),
    ]
)
