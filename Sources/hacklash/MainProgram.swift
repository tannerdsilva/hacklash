import wireguard_userspace
import NIO
import RAW_dh25519
import Logging
import ServiceLifecycle

@main
struct MainProgram {
	static func main() async throws {
		let pk = try PrivateKey()
		let sk = PublicKey(pk)
		let wg = WireguardInterface(loopGroupProvider: MultiThreadedEventLoopGroup(numberOfThreads: 1), staticPublicKey:sk)
		
		let allServices:[any Service] = [wg]
		let serviceGroup = ServiceGroup(services:allServices, gracefulShutdownSignals: [.sigint], logger:Logger(label:"hacklash"))

		try await serviceGroup.run()

	}
}