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

	init(publicKey:PublicKey) throws {
		var ci = try wgHash([UInt8]("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))
		var hi:Result32 = try ci.RAW_access {
			return try wgHash([UInt8]($0) + [UInt8]("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))
		}
		try publicKey.RAW_access { publicKeyPtr in
			try hi.RAW_access { hiPtr in
				hi = try wgHash([UInt8](hiPtr) + [UInt8](publicKeyPtr))
			}
		}
		let ephPrivate = try PrivateKey()
		let ephPublic = PublicKey(ephPrivate)
		try ephPublic.RAW_access { ephPublicPtr in
			ci = try kdf(n:1, key:PublicKey(RAW_staticbuff:&ci), data:[UInt8](ephPublicPtr)).first!
		}
		hi = try hi.RAW_access { hiPtr in
			try ephPublic.RAW_access { ephPublicPtr in
				return try wgHash([UInt8](hiPtr) + [UInt8](ephPublicPtr))
			}
		}
	}
}
