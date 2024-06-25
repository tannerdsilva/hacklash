import wireguard_userspace
import NIO

@main
struct MainProgram {
	static func main() async throws {
		let wg = WireguardConnection(loopGroupProvider: MultiThreadedEventLoopGroup(numberOfThreads: 1))
		do {
			try await wg.connect(address: "96.126.112.198", port: 29300)
		} catch {
			print("Error: \(error)")
		}

	}
}