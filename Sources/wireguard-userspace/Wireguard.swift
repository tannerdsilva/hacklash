import RAW
import NIO
import RAW_dh25519
import ServiceLifecycle
import WebCore

public typealias Key = RAW_dh25519.PublicKey

public final class WireguardInterface:Service {
	let elg: EventLoopGroup
	let listeningPort:Int
	let staticPublicKey:PublicKey

	let connectedChannel:EventLoopFuture<Channel>
	let peerRouter:PeerRouter

	public init(loopGroupProvider:EventLoopGroup, staticPublicKey:PublicKey, listeningPort:Int? = nil) {
		self.elg = loopGroupProvider

		let lp:Int
		if let listeningPort = listeningPort {
			self.listeningPort = listeningPort
			lp = listeningPort
		} else {
			lp = Int.random(in:10000..<16000)
			self.listeningPort = lp
		}

		let pr = PeerRouter()
		self.peerRouter = pr
		self.staticPublicKey = staticPublicKey
		self.connectedChannel = DatagramBootstrap(group:elg.next())
			.channelOption(ChannelOptions.socketOption(.so_reuseaddr), value:1)
			.channelInitializer({ [pr] channel in
				return channel.pipeline.addHandler(pr)
			}).bind(host:"0.0.0.0", port:lp)
	}

	public func run() async throws {
		let channel = try await self.connectedChannel.get()
		try await gracefulShutdown()
		try? await channel.close()
	}
}

// Handler to process incoming and outgoing data
internal final class PeerRouter:ChannelDuplexHandler {
	internal typealias InboundIn = AddressedEnvelope<ByteBuffer>
	internal typealias InboundOut = AddressedEnvelope<ByteBuffer>
	internal typealias OutboundIn = AddressedEnvelope<ByteBuffer>
	internal typealias OutboundOut = AddressedEnvelope<ByteBuffer>

	private var handshakeStages = [SocketAddress:Int]()
	
	internal init() {}

	internal func channelActive(context:ChannelHandlerContext) {
		
	}
	
	func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		let envelope = self.unwrapInboundIn(data)
		
	}

	func errorCaught(context: ChannelHandlerContext, error: Error) {
		print("Error: \(error)")
		context.close(promise: nil)
	}
}
