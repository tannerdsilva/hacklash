import RAW
import RAW_dh25519
import RAW_chachapoly

@RAW_staticbuff(bytes:3)
internal struct Reserved:Sendable {
	internal init() {
		self = Self(RAW_staticbuff:[0, 0, 0])
	}
}


internal struct HandshakeInitiationMessage:Sendable {
	internal static func computeInitiationValues(iPublicKey:PublicKey, rPublicKey:PublicKey, into destinationPayload:UnsafeMutablePointer<Payload?>? = nil) throws -> (c:Result32, h:Result32, k:Result32) {
		// step 1: calculate the hash of the static construction string
		var c = try wgHash([UInt8]("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))

		// step 2: h = hash(ci || identifier)
		var h:Result32 = try c.RAW_access {
			return try wgHash([UInt8]($0) + [UInt8]("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))
		}

		// step 3: h = hash(h || rPublicKey public key)
		h = try rPublicKey.RAW_access { publicKeyPtr in
			return try h.RAW_access { hPtr in
				return try wgHash([UInt8](hPtr) + [UInt8](publicKeyPtr))
			}
		}

		// step 4: generate ephemeral keys
		let ephiPrivate = try PrivateKey()
		let ephiPublic = PublicKey(ephiPrivate)

		// step 5: c = KDF^1(c, e.Public)
		c =  try wgKDF(key:PublicKey(RAW_staticbuff:&c), data:ephiPublic, returning:(Result32).self)

		// step 6: assign e.Public to the ephemeral field
		let msgEphemeral = ephiPublic

		// step 7: k = KDF^2(c, e.Public)
		h = try h.RAW_access { hPtr in
			try ephiPublic.RAW_access { ephPublicPtr in
				return try wgHash([UInt8](hPtr) + [UInt8](ephPublicPtr))
			}
		}

		// step 8: (c, k) = KDF^2(c, dh(eiPriv, srPublic))
		var k:Result32
		(c, k) = try h.RAW_access { hPtr in
			return try wgKDF(key:PublicKey(RAW_staticbuff:&c), data:try dhKeyExchange(privateKey:ephiPrivate, publicKey:rPublicKey), returning:(Result32, Result32).self)
		}

		// step 9: msg.static = AEAD(k, 0, siPublic, h)
		var (msgStatic, _) = try k.RAW_access_staticbuff { kPtr in
			try h.RAW_access { hPtr in
				return try aeadEncrypt(key:kPtr.load(as:Key32.self), counter:0, text:iPublicKey, aad:[UInt8](hPtr))
			}
		}

		// step 10: h = hash(h || msg.static)
		h = try h.RAW_access({ hPtr in
			try msgStatic.RAW_access({ msgStaticPtr in
				return try wgHash([UInt8](hPtr) + [UInt8](msgStaticPtr))
			})
		})

		// step 11: c, k) = kdf^2(c, dh(sipriv, srpub))
		(c, k) = try h.RAW_access({ hPtr in
			return try wgKDF(key:PublicKey(RAW_staticbuff:&c), data:[UInt8](hPtr), returning:(Result32, Result32).self)
		})

		// step 12: msg.timestamp = AEAD(k, 0, timestamp(), h)
		let ts = try h.RAW_access({ hPtr in
			try k.RAW_access_staticbuff({ kPtr in
				try aeadEncrypt(key:kPtr.load(as:Key32.self), counter:0, text:TAI64N(), aad:[UInt8](hPtr)).0.RAW_access({ ptrIn in
					return TAI64N(RAW_staticbuff:ptrIn.baseAddress!)
				})
			})
		})

		// step 13: h = hash(h || msg.timestamp)
		h = try h.RAW_access({ hPtr in
			try ts.RAW_access({ timestampPtr in
				return try wgHash([UInt8](hPtr) + [UInt8](timestampPtr))
			})
		})

		if destinationPayload != nil {
			destinationPayload!.pointee = Payload(initiatorPeerIndex:try PeerIndex.random(), ephemeral:msgEphemeral, staticRegion:Result32(RAW_staticbuff:&msgStatic), timestamp:ts)
		}

		return (c, h, k)
	}

	/// this message is described in the wireguard whitepaper in section 5.4.2
	@RAW_staticbuff(concat:RAW_byte, Reserved, PeerIndex, PublicKey, Result32, TAI64N)
	internal struct Payload:Sendable {
		/// message type
		internal let typeContent:RAW_byte
		/// reserved field
		internal let reservedContent:Reserved
		/// initiator's peer index
		internal let initiatorPeerIndex:PeerIndex
		/// ephemeral key content
		internal let ephemeral:PublicKey
		/// static region of the message
		internal let staticRegion:Result32
		/// timestamp associated with the message
		internal let timestamp:TAI64N

		/// initializes a new HandshakeInitiationMessage
		fileprivate init(initiatorPeerIndex:PeerIndex, ephemeral:PublicKey, staticRegion:Result32, timestamp:TAI64N) {
			typeContent = 0x1
			reservedContent = Reserved()
			self.initiatorPeerIndex = initiatorPeerIndex
			self.ephemeral = ephemeral
			self.staticRegion = staticRegion
			self.timestamp = timestamp
		}
	}	
}

fileprivate struct InitiationResponseMessage:Sendable {
	fileprivate struct Payload:Sendable {
		let typeContent:RAW_byte
		let reservedContent:Reserved
		let senderIndex:PeerIndex
		let receiverIndex:PeerIndex
		let ephemeral:PublicKey
		let empty:Tag

		// init(receivingResponse:borrowing PeerIndex) throws {
		// 	typeContent = 0x2
		// 	let ephPrivate = try PrivateKey()
		// 	let ephPublic = PublicKey(ephPrivate)
		// 	// var cr = wgKDF(
		// }
	
	}
}