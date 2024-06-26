import RAW
import RAW_dh25519
import RAW_chachapoly

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:false)
internal struct Zeros:Sendable, ExpressibleByIntegerLiteral {}

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:false)
internal struct Counter:Sendable {}

@RAW_staticbuff(concat:Zeros, Counter)
internal struct CountedNonce:Sendable {
	internal let zeros:Zeros
	internal let counter:Counter
	internal init(counter:UInt64) {
		self.zeros = 0
		self.counter = Counter(RAW_native:counter)
	}
}

internal func aeadEncrypt<A, D>(key:Key32, counter:UInt64, text:borrowing A, aad:consuming D) throws -> ([UInt8], Tag) where A:RAW_accessible, D:RAW_accessible {
	var context = RAW_chachapoly.Context(key:key)
	return try text.RAW_access { textBuff in
		let cipherText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:textBuff.count)
		defer { cipherText.deallocate() }
		let tag = try aad.RAW_access { aadBuff in
			return try CountedNonce(counter: counter).RAW_access_staticbuff { 
				try context.encrypt(nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:textBuff, output:cipherText.baseAddress!)
			}
		}
		return (Array(cipherText), tag)
	}
}

internal func aeadDecrypt<A, D>(key:Key32, counter:UInt64, cipherText:borrowing A, aad:consuming D, tag:Tag) throws -> [UInt8] where A:RAW_accessible, D:RAW_accessible {
	var context = RAW_chachapoly.Context(key:key)
	return try cipherText.RAW_access { cipherTextBuff in
		let plainText = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:cipherTextBuff.count)
		defer { plainText.deallocate() }
		try aad.RAW_access { aadBuff in
			try CountedNonce(counter: counter).RAW_access_staticbuff { 
				try context.decrypt(tag:tag, nonce:$0.load(as:Nonce.self), associatedData:aadBuff, inputData:cipherTextBuff, output:plainText.baseAddress!)
			}
		}
		return Array(plainText)
	}
}