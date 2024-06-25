import RAW
import RAW_dh25519
import RAW_chachapoly

@RAW_staticbuff(bytes:3)
fileprivate struct Reserved:Sendable {}
@RAW_staticbuff(bytes:4)
fileprivate struct SenderIndex:Sendable {}

@RAW_staticbuff(concat:RAW_byte, Reserved, SenderIndex, PublicKey)
fileprivate struct HandshakeInitiationMessage:Sendable {

	let typeContent:RAW_byte
	let reservedContent:Reserved
	let senderIndexContent:SenderIndex
	let ephemeral:PublicKey
	
}
