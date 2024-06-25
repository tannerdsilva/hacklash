import RAW
import NIO
import RAW_dh25519

public typealias Key = RAW_dh25519.PublicKey

public final class WireguardConnection {

	// EventLoopGroup to handle async operations
	let elg: EventLoopGroup

	var connectedChannel:Channel?

	public init(loopGroupProvider: EventLoopGroup) {
		self.elg = loopGroupProvider
		self.connectedChannel = nil
	}

	public func connect(address:String, port:Int) async throws {
		 self.connectedChannel = try await DatagramBootstrap(group:elg.next())
			.channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
			.channelInitializer({ channel in
				print("Connected to \(address):\(port)")
				return channel.pipeline.addHandler(UDPTunnel(host: address, port: port))
			}).bind(host: "0.0.0.0", port:Int.random(in:10000..<16000)).get()
	}

	
}

// Handler to process incoming and outgoing data
final class UDPTunnel: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>

	let host: String
	let port: Int

	init(host: String, port: Int) {
		self.host = host
		self.port = port
	}

    func channelActive(context: ChannelHandlerContext) {
		print("Channel active")
        let message = "Hello from SwiftNIO UDP Client!"
        var buffer = context.channel.allocator.buffer(capacity: message.utf8.count)
        buffer.writeString(message)
        
        let remoteAddress = try! SocketAddress(ipAddress: host, port: port)
        let envelope = AddressedEnvelope(remoteAddress: remoteAddress, data: buffer)
        context.writeAndFlush(self.wrapOutboundOut(envelope), promise: nil)
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = self.unwrapInboundIn(data)
        if let receivedString = envelope.data.getString(at: 0, length: envelope.data.readableBytes) {
            print("Received: \(receivedString)")
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("Error: \(error)")
        context.close(promise: nil)
    }
}
